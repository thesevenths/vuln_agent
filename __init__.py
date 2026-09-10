"""
`agent` 包初始化文件。

这个文件当前不承载业务逻辑，主要有两个作用：
1. 把 `D:\\agent\\agent` 声明为可导入的 Python package
2. 给维护者一个统一入口，了解这个包的核心模块职责

模块职责速览：
- `main.py`：CLI/REPL 入口
- `tools.py`：高层工具封装（JoernTool/DBTool）
- `graph.py`：流程编排
- `joern_vuln_scanner.py`：核心扫描引擎
- `chains.py`：报告/摘要生成函数
- `state.py`：会话状态
"""

from . import config  # noqa: F401  # 以包方式 import agent 时也加载 .env