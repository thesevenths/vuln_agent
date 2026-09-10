"""
LangGraph 节点实现。若系统已安装 langgraph，会构建实际 langgraph 节点；否则提供轻量 Node 以便本地执行。
"""
from typing import Any, Callable

HAS_LANGGRAPH = False
try:
    # langgraph API may differ; detect availability only
    import langgraph  # type: ignore
    HAS_LANGGRAPH = True
except Exception:
    # 运行环境没有 langgraph 也不应该阻塞功能；
    # 我们会自动回退到本地 Node 包装器实现。
    HAS_LANGGRAPH = False

class Node:
    def __init__(self, name: str, func: Callable[..., Any]):
        """
        初始化一个轻量节点包装器。

        Args:
            name: 节点名，用于调试和日志定位。
            func: 节点执行函数，接收关键字参数并返回任意结果。
        """
        self.name = name
        self.func = func
        self.inputs = {}
        self.outputs = None

    def run(self, **kwargs):
        """
        执行节点函数并缓存本次输入输出。

        Args:
            **kwargs: 传给节点函数的参数。

        Returns:
            节点函数返回值。
        """
        # 保存所有历史输入字段，方便后续串联节点时做状态传递。
        # 这里使用 update 而不是直接赋值，允许逐步累积上下文。
        self.inputs.update(kwargs)
        # 统一以关键字参数方式调用，避免调用方参数位置顺序耦合。
        self.outputs = self.func(**self.inputs)
        return self.outputs

def make_node(name: str, func: Callable[..., Any]):
    """
    创建节点对象，优先尝试使用真实 langgraph 节点类型。

    Args:
        name: 节点名。
        func: 节点执行函数。

    Returns:
        如果运行环境支持 langgraph，则返回其原生节点；
        否则返回本地 `Node` 包装器。
    """
    if HAS_LANGGRAPH:
        # 如果 langgraph 可用，优先尝试复用其原生 Node 类型，
        # 这样后续迁移到真正的图执行引擎时成本更低。
        try:
            # 尝试动态导入，避免把 langgraph 设成硬依赖。
            lg = __import__("langgraph")
            if hasattr(lg, "Node"):
                return lg.Node(name=name, func=func)
        except Exception:
            # 即使导入/构造失败，也不要中断主流程，继续回退本地实现。
            pass
    return Node(name, func)