"""
统一加载 `.env` 到 `os.environ`。

在进程启动时 import 本模块一次即可（幂等）；其它模块继续用 `os.environ.get()` 读配置，
无需各自调用 `load_dotenv()`。

会读取与本文件同目录的 `.env`（即 `agent/.env`）。

主要环境变量（按模块）：
- LLM：`QWEN_PLUS_API_KEY`, `QWEN_PLUS_BASE_URL`, `QWEN_PLUS_MODEL`（llm_client / chains / planner）
- PostgreSQL：`PG_DSN` 或 `DB_NAME`, `USER_NAME`, `PASS_WORD`, `DB_HOST`, `DB_PORT`（db_connector）
- Joern：`JOERN_URL`, `JOERN_MAX_FLOWS_PER_QUERY`, `JOERN_HARD_BACKTRACE_TOP_CALLER_BODIES`, `JOERN_ENABLE_REFUTATION`, …（joern_vuln_scanner / queries）
- Java 反射：扫描 Java 时自动追加 `java_reflection_*` 保守查询（见 queries.java_reflection_queries）
- Agent CLI：`AGENT_LANGUAGE`, `AGENT_MAX_ITERS`, `AGENT_AUDIT_LOG_PATH`, `AGENT_LOCAL_SOURCE_PATH`（main / planner）
- 逻辑漏洞扫描：`LOGIC_SCAN_MAX_CANDIDATES`, `LOGIC_SCAN_MAX_CANDIDATES_FLOOR`, `LOGIC_SCAN_DEFAULT_CWE_FOCUS`, `LOGIC_SCAN_HIGH_HIT_THRESHOLD`（logic_scan_settings.py）
- 文件读写：`AGENT_FILE_READ_ROOTS`, `AGENT_REPORT_DIR`, `AGENT_AUTO_SAVE_REPORT`, `AGENT_FILE_MAX_READ_BYTES`（file_tools / FileTool）

已在 import 时加载 config 的模块：main, tools, joern_vuln_scanner, queries, llm_client,
chains, planner, db_connector, 以及包 `__init__`。
"""

from pathlib import Path

_ENV_LOADED = False


def ensure_env_loaded() -> None:
    """将项目根目录下的 `.env` 注入环境变量（幂等，可重复调用）。"""
    global _ENV_LOADED
    if _ENV_LOADED:
        return

    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    package_dir = Path(__file__).resolve().parent
    env_file = package_dir / ".env"
    if env_file.is_file():
        load_dotenv(env_file)
    else:
        load_dotenv()

    _ENV_LOADED = True


ensure_env_loaded()
