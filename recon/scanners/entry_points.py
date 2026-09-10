"""
recon/scanners/entry_points.py — 外部入口发现

消费适配器解析后的 EntryPoint 列表，合并所有类型：
- HTTP（REST Controller）
- WebSocket（@ServerEndpoint, @OnMessage）
- MQ（@KafkaListener, @RabbitListener）
- Scheduled（@Scheduled, Quartz）
- File Upload（MultipartFile）
- RPC（gRPC, Dubbo）
- Deserialization（readObject, ObjectMapper）

并对结果做去重和排序。
"""
from __future__ import annotations

import logging
from typing import Dict, List, Set

from recon.adapters.base import ReconAdapter
from recon.models import EntryPoint

logger = logging.getLogger(__name__)


def scan_entry_points(
    query_results: Dict[str, str],
    adapter: ReconAdapter,
) -> List[EntryPoint]:
    """
    从 Joern 查询结果中发现所有外部入口。

    Args:
        query_results: Joern 批量查询的原始结果（name -> raw output）。
        adapter: 语言/框架适配器（负责解析具体格式）。

    Returns:
        去重后的 EntryPoint 列表，按 entry_type 分组、handler 排序。
    """
    entries = adapter.parse_entry_points(query_results)
    logger.info("适配器解析入口点: %d 个", len(entries))

    # 去重（按 handler + entry_type）
    seen: Set[str] = set()
    unique: List[EntryPoint] = []
    for ep in entries:
        key = f"{ep.handler}|{ep.entry_type}"
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    # 按类型分组统计
    type_counts: Dict[str, int] = {}
    for ep in unique:
        type_counts[ep.entry_type] = type_counts.get(ep.entry_type, 0) + 1

    for t, count in sorted(type_counts.items()):
        logger.info("  入口类型 %s: %d", t, count)

    # 排序：http 优先，然后按 handler 字母序
    _TYPE_ORDER = {"http": 0, "websocket": 1, "file_upload": 2, "mq": 3, "rpc": 4, "scheduled": 5, "deserialization": 6}
    unique.sort(key=lambda e: (_TYPE_ORDER.get(e.entry_type, 9), e.handler))

    logger.info("去重后入口点: %d 个", len(unique))
    return unique


def build_content_type_map(
    query_results: Dict[str, str],
    adapter: ReconAdapter,
) -> Dict[str, List[str]]:
    """
    从 content_type_consumers 查询结果构建 Content-Type → handler 映射。

    用于后续 XXE（XML）、反序列化（JSON）、CSRF（form-data）检测。

    Returns:
        {"application/xml": ["handler1", ...], "application/json": [...], ...}
    """
    ct_map: Dict[str, List[str]] = {}
    raw = query_results.get("content_type_consumers", "")
    if not raw:
        return ct_map

    import re
    for line in raw.splitlines():
        line = line.strip().strip('",')
        if "CONTENT_TYPE" not in line:
            continue
        handler_m = re.search(r"CONTENT_TYPE\s*\|\s*([^\s|]+)", line)
        types_m = re.search(r"types=(.+?)$", line)
        if not handler_m or not types_m:
            continue
        handler = handler_m.group(1).strip()
        types_raw = types_m.group(1).strip()

        # 从注解代码中提取 content type
        for ct in ("application/xml", "text/xml", "application/json",
                    "multipart/form-data", "application/x-www-form-urlencoded"):
            if ct.replace("/", "\\/") in types_raw or ct in types_raw or ct.split("/")[1] in types_raw:
                ct_map.setdefault(ct, []).append(handler)

    for ct, handlers in ct_map.items():
        logger.info("  Content-Type %s: %d 个入口", ct, len(handlers))

    return ct_map
