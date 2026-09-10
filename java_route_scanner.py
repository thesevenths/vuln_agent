"""
Lightweight Java Web route discovery (inspired by java-route-mapper).

Static regex scan — fast attack-surface index for Planner/Joern follow-up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
import re


ROUTE_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    (
        "spring_mapping",
        re.compile(
            r"@(?P<ann>RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)"
            r"\s*\((?P<args>[^)]*)\)",
            re.MULTILINE,
        ),
    ),
    (
        "jaxrs",
        re.compile(
            r"@(?P<ann>Path|GET|POST|PUT|DELETE)\s*\((?P<args>[^)]*)\)",
            re.MULTILINE,
        ),
    ),
)

CLASS_PATTERN = re.compile(r"class\s+(\w+)")
METHOD_PATTERN = re.compile(
    r"(?:public|protected|private)?\s*[\w<>,\s\[\]]+\s+(\w+)\s*\([^;{]*\)\s*\{",
    re.MULTILINE,
)
STRING_LITERAL = re.compile(r'["\']([^"\']+)["\']')


@dataclass
class RouteHit:
    file_path: str
    line_no: int
    http_method: str
    path: str
    class_name: str
    method_name: str
    framework: str
    annotation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file_path,
            "line": self.line_no,
            "http_method": self.http_method,
            "path": self.path,
            "class": self.class_name,
            "method": self.method_name,
            "framework": self.framework,
            "annotation": self.annotation,
        }


def _guess_class_name(text: str, before_pos: int) -> str:
    prefix = text[:before_pos]
    matches = list(CLASS_PATTERN.finditer(prefix))
    return matches[-1].group(1) if matches else "Unknown"

def _guess_method_name(text: str, line_start: int, line_end: int) -> str:
    window = text[line_start: min(len(text), line_end + 400)]
    match = METHOD_PATTERN.search(window)
    return match.group(1) if match else "unknown"

def _extract_path_from_args(args: str) -> str:
    if not args:
        return "/"
    # value = "/api/foo" or path = "/api/foo"
    for key in ("value", "path"):
        m = re.search(rf"{key}\s*=\s*[\"']([^\"']+)[\"']", args)
        if m:
            return m.group(1)
    m = STRING_LITERAL.search(args)
    if m:
        return m.group(1)
    return "/"

def _http_method_from_annotation(ann: str, args: str) -> str:
    ann_lower = ann.lower()
    if "get" in ann_lower:
        return "GET"
    if "post" in ann_lower:
        return "POST"
    if "put" in ann_lower:
        return "PUT"
    if "delete" in ann_lower:
        return "DELETE"
    if "patch" in ann_lower:
        return "PATCH"
    m = re.search(r"RequestMethod\.(\w+)", args)
    if m:
        return m.group(1).upper()
    m = re.search(r"method\s*=\s*\{?\s*RequestMethod\.(\w+)", args)
    if m:
        return m.group(1).upper()
    if ann in ("GET", "POST", "PUT", "DELETE"):
        return ann
    return "ANY"


def scan_java_routes(
    root_dir: str,
    *,
    max_files: int = 800,
    max_hits: int = 500,
) -> Dict[str, Any]:
    root = Path(root_dir)
    if not root.is_dir():
        return {"ok": False, "error": f"目录不存在: {root_dir}", "routes": []}

    hits: List[RouteHit] = []
    scanned_files = 0
    skip_dirs = {".git", "target", "build", "node_modules", ".gradle", "out", "dist"}

    for path in root.rglob("*.java"):
        if any(part in skip_dirs for part in path.parts):
            continue
        scanned_files += 1
        if scanned_files > max_files:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for framework, pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(text):
                ann = match.group("ann")
                args = match.group("args") or ""
                line_no = text[: match.start()].count("\n") + 1
                hits.append(
                    RouteHit(
                        file_path=rel,
                        line_no=line_no,
                        http_method=_http_method_from_annotation(ann, args),
                        path=_extract_path_from_args(args),
                        class_name=_guess_class_name(text, match.start()),
                        method_name=_guess_method_name(text, match.start(), match.end()),
                        framework="spring" if "spring" in framework or "Mapping" in ann else "jaxrs",
                        annotation=ann,
                    )
                )
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break

    routes = [h.to_dict() for h in hits]
    by_method: Dict[str, int] = {}
    for r in routes:
        m = r.get("http_method", "ANY")
        by_method[m] = by_method.get(m, 0) + 1

    return {
        "ok": True,
        "root_dir": str(root),
        "scanned_files": scanned_files,
        "route_count": len(routes),
        "by_http_method": by_method,
        "routes": routes,
    }


def format_routes_markdown(scan_result: Dict[str, Any], *, max_rows: int = 80) -> str:
    if not scan_result.get("ok"):
        return f"# Java 路由扫描失败\n\n{scan_result.get('error', 'unknown')}\n"
    lines = [
        "# Java Web 路由索引（静态扫描）",
        "",
        f"- 根目录: `{scan_result.get('root_dir', '')}`",
        f"- 扫描文件数: {scan_result.get('scanned_files', 0)}",
        f"- 路由条数: {scan_result.get('route_count', 0)}",
        "",
        "| # | HTTP | 路径 | 类.方法 | 文件:行 |",
        "|---|------|------|---------|---------|",
    ]
    for idx, route in enumerate(list(scan_result.get("routes") or [])[:max_rows], start=1):
        loc = f"{route.get('file')}:{route.get('line')}"
        lines.append(
            f"| {idx} | {route.get('http_method', '')} | `{route.get('path', '')}` | "
            f"`{route.get('class', '')}.{route.get('method', '')}` | {loc} |"
        )
    if int(scan_result.get("route_count", 0)) > max_rows:
        lines.append(f"\n> 仅展示前 {max_rows} 条，完整列表见 state.metadata.java_routes")
    lines.append("")
    lines.append("> 下一步建议: 对 P0 路由用 java-route-tracer 手册 + FileTool 追调用链，再用 Joern 验证污点。")
    return "\n".join(lines)
