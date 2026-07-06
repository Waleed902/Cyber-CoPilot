"""Minimal LLM helper for tools that expect get_llm()."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from loguru import logger
from openai import OpenAI

from src.sdk.key_manager import get_key_manager


@dataclass
class LLMWrapper:
    client: OpenAI
    model: str
    key_manager: object

    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as e:
            try:
                self.key_manager.record_failure(str(e))
            except Exception:
                pass
            raise

        content = ""
        if response and getattr(response, "choices", None):
            message = response.choices[0].message if response.choices[0] else None
            if message and message.content:
                content = message.content

        try:
            if response and getattr(response, "usage", None):
                self.key_manager.record_success(response.usage.total_tokens or 0)
        except Exception as e:
            logger.debug(f"LLM usage tracking skipped: {e}")

        return content


def get_llm() -> LLMWrapper:
    """Return an LLM wrapper using the current configured provider."""
    km = get_key_manager()
    return LLMWrapper(client=km.get_client(), model=km.get_model(), key_manager=km)


__all__ = ["LLMWrapper", "get_llm"]
