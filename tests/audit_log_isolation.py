"""集成测试 Planner 审计日志目录（与正式 planner_audit_logs/ 隔离）。"""

from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, Optional
from unittest.mock import patch

# 仓库根目录下固定目录（用户指定拼写 integret_test）
INTEGRATION_AUDIT_LOG_DIR = (
    Path(__file__).resolve().parent.parent / "planner_audit_logs_integret_test"
)


def integration_audit_log_path(*, prefix: str = "planner_audit") -> Path:
    """生成带时间戳的 JSONL 路径，并确保目录存在。"""
    INTEGRATION_AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return INTEGRATION_AUDIT_LOG_DIR / f"{prefix}_{stamp}.jsonl"


@contextmanager
def isolated_planner_audit_log(
    *,
    extra_env: Optional[Dict[str, str]] = None,
    log_basename: str = "planner_audit",
) -> Iterator[str]:
    """
    将 AGENT_AUDIT_LOG_PATH 指向 planner_audit_logs_integret_test/ 下的 JSONL。

    日志会保留在磁盘上供排查；不会写入正式目录 planner_audit_logs/。

    Yields:
        审计日志 JSONL 的绝对路径字符串。
    """
    log_path = integration_audit_log_path(prefix=log_basename)
    env: Dict[str, str] = {"AGENT_AUDIT_LOG_PATH": str(log_path)}
    if extra_env:
        env.update(extra_env)
    with patch.dict(os.environ, env, clear=False):
        yield str(log_path)
