"""
`db_connector.py` 封装 PostgreSQL 连接细节。

设计目标：
1. 上层代码不直接碰 `psycopg2.connect(...)`
2. 同时兼容两种配置方式：
   - 一条完整的 `PG_DSN`
   - 拆分的主机/端口/用户名/密码环境变量
3. 提供简单稳定的上下文管理接口，方便 `with PostgresDB() as db:` 使用
"""

import logging
import os
from typing import Any, List, Optional, Tuple

import config  # noqa: F401  # 非 main 入口时仍加载 .env

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class PostgresDB:
    """
    PostgreSQL 连接包装器。

    这个类主要给当前项目里的 `DBTool` 和一些旧脚本使用，
    提供统一的连接、执行 SQL、提交/回滚和关闭资源能力。
    """

    def __init__(self, dsn: Optional[str] = None):
        """
        初始化数据库连接配置。

        Args:
            dsn: 可选完整连接串。若不提供，则从环境变量读取分散配置项。
        """
        self.dsn = dsn or os.getenv("PG_DSN")
        self.db_name = os.getenv("DB_NAME")
        self.user = os.getenv("USER_NAME")
        self.password = os.getenv("PASS_WORD")
        self.host = os.getenv("DB_HOST")
        self.port = os.getenv("DB_PORT")
        self.conn = None
        self.cursor = None

    def _build_connect_kwargs(self) -> dict:
        """
        构造 `psycopg2.connect(...)` 所需参数。

        Returns:
            一个可直接传给 `psycopg2.connect` 的参数字典。
        """
        if self.dsn:
            # DSN 模式：一条连接串包含所有信息，优先级最高。
            return {"dsn": self.dsn}

        if not all([self.db_name, self.user, self.password, self.host, self.port]):
            raise EnvironmentError(
                "数据库环境变量缺失。请设置 `PG_DSN` 或补齐 `DB_NAME/USER_NAME/PASS_WORD/DB_HOST/DB_PORT`。"
            )

        return {
            "dbname": self.db_name,
            "user": self.user,
            "password": self.password,
            "host": self.host,
            "port": self.port,
            "connect_timeout": 10,
        }

    def connect(self):
        """
        建立数据库连接。

        Returns:
            活跃的 psycopg2 connection 对象。
        """
        if self.conn is None or self.conn.closed:
            connect_kwargs = self._build_connect_kwargs()
            logger.info("正在连接 PostgreSQL")
            if "dsn" in connect_kwargs:
                self.conn = psycopg2.connect(connect_kwargs["dsn"])
            else:
                self.conn = psycopg2.connect(**connect_kwargs)
        # 连接复用：若连接仍有效，直接返回，避免重复握手开销。
        return self.conn

    def get_cursor(self):
        """
        获取可用游标。

        Returns:
            使用 `RealDictCursor` 构造的游标，查询结果会更易读。
        """
        if self.conn is None or self.conn.closed:
            self.connect()
        if self.cursor is None or self.cursor.closed:
            # `RealDictCursor` 能让结果按列名返回，更适合后续标准化处理。
            self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return self.cursor

    def execute_query(self, query: str, params: Optional[Tuple] = None) -> List[Any]:
        """
        执行一条 SQL。

        Args:
            query: SQL 语句。
            params: 可选参数元组，用于参数化查询。

        Returns:
            如果是查询语句，则返回结果列表；否则返回空列表。
        """
        cursor = self.get_cursor()
        try:
            # 参数和 SQL 分离，避免把变量直接拼进 SQL 造成注入风险。
            cursor.execute(query, params)
            if cursor.description:
                # 有 description 说明是查询语句，返回结果集。
                return cursor.fetchall()
            # 非 SELECT 场景在这里直接提交，保持调用方接口简单。
            self.conn.commit()
            return []
        except Exception as exc:
            logger.error("执行查询失败: %s", exc)
            # 一旦某条语句失败，主动回滚本次事务，避免连接进入脏状态。
            self.conn.rollback()
            raise

    def execute(self, sql: str, params=None):
        """
        `execute_query` 的兼容别名。

        Args:
            sql: SQL 语句。
            params: 参数元组。

        Returns:
            与 `execute_query` 相同。
        """
        return self.execute_query(sql, params)

    def close(self):
        """
        关闭游标和连接。
        """
        if self.cursor and not self.cursor.closed:
            self.cursor.close()
        if self.conn and not self.conn.closed:
            self.conn.close()
        # 清空引用，避免调用方误以为还能继续复用旧连接对象。
        self.cursor = None
        self.conn = None

    def __enter__(self):
        """
        进入 `with` 语句时自动建立连接。
        """
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        退出 `with` 语句时做回滚和资源清理。

        Args:
            exc_type: 异常类型。
            exc_val: 异常实例。
            exc_tb: traceback。

        Returns:
            `False`，表示不要吞掉异常。
        """
        if exc_type and self.conn and not self.conn.closed:
            # with 块内抛异常时回滚，保持事务语义一致。
            self.conn.rollback()
        self.close()
        return False