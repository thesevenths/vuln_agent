"""
`llm_client.py` 封装当前项目使用的大模型访问方式。

这个模块的目标不是暴露 OpenAI SDK 的所有能力，
而是提供当前项目真正需要的两种高层操作：

- `complete`：拿到普通文本结果
- `complete_json`：拿到结构化 JSON 结果

这样上层逻辑就不需要反复处理：
- API key/base_url/model 的初始化
- Markdown 代码块清理
- JSON 容错解析
"""

import config  # noqa: F401

import json
import logging
import os
import re
from typing import Any, Dict, Optional

from openai import OpenAI

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _strip_markdown_fence(text: str) -> str:
    """
    去掉大模型输出外层的 Markdown 代码块包裹。

    Args:
        text: 模型返回文本。

    Returns:
        去掉 ```json / ```markdown 等围栏后的纯文本。
    """
    if not text:
        return ""
    return re.sub(r"^```(?:json|markdown|md|text)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE)


class LLMClient:
    """
    面向当前项目场景的大模型客户端。

    这个类屏蔽了底层 SDK 细节，让上层只需要关心：
    - system prompt 是什么
    - user prompt 是什么
    - 期待普通文本还是 JSON
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """
        初始化 LLM 客户端。

        Args:
            api_key: API Key；不传则读取环境变量 `QWEN_PLUS_API_KEY`。
            base_url: OpenAI-compatible 服务地址。
            model: 模型名。
        """
        self.api_key = api_key or os.environ.get("QWEN_PLUS_API_KEY", "")
        self.base_url = base_url or os.environ.get(
            "QWEN_PLUS_BASE_URL",
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        self.model = model or os.environ.get("QWEN_PLUS_MODEL", "qwen-plus")

        if not self.api_key:
            raise RuntimeError("缺少 QWEN_PLUS_API_KEY，无法初始化 LLMClient")

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def complete(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 3500,
    ) -> str:
        """
        执行一次普通文本补全请求。

        Args:
            system_prompt: 系统提示词，定义模型角色和硬约束。
            user_prompt: 用户提示词，包含当前任务和上下文。
            temperature: 采样温度；安全分析场景一般使用较低值以保证稳定性。
            max_tokens: 最大输出 token 数。

        Returns:
            模型返回的文本结果。
        """
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return (response.choices[0].message.content or "").strip()

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 600,
        fallback: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        执行一次“预期返回 JSON”的补全请求。

        Args:
            system_prompt: 系统提示词。
            user_prompt: 用户提示词。
            temperature: 采样温度。
            max_tokens: 输出上限。
            fallback: 当 JSON 解析失败时返回的默认值。

        Returns:
            解析后的 JSON 字典；如果解析失败则返回 fallback 或空字典。
        """
        raw_text = self.complete(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        # 先去掉可能的 markdown 外壳，再做 JSON 解析，提高容错性。
        cleaned_text = _strip_markdown_fence(raw_text)

        try:
            return json.loads(cleaned_text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned_text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    logger.warning(
                        "LLM JSON 解析失败，返回 fallback | raw_text 前 500 字: %s",
                        raw_text[:500].replace("\n", " "),
                    )
            else:
                logger.warning(
                    "LLM JSON 解析失败（未找到 JSON 块），返回 fallback | raw_text 前 500 字: %s",
                    raw_text[:500].replace("\n", " "),
                )
            return fallback or {}


def get_default_llm_client() -> LLMClient:
    """
    构造默认的 LLM 客户端。

    Returns:
        使用当前环境变量配置初始化好的 `LLMClient`。
    """
    return LLMClient()