"""OpenAIProvider -- Provider backed by the OpenAI Chat Completions API.

The system prompt is sent as the first chat message. ``cache`` is accepted but
not applied: OpenAI caches long prompts automatically server-side, with no
request parameter to set.

The client is injectable so the mapping can be tested without the SDK or a key.
"""

from __future__ import annotations

from typing import Any

from codejury.providers.base import CompletionResult, Message, Provider
from codejury.providers.openai_format import choice_text


class OpenAIProvider(Provider):
    def __init__(self, *, api_key: str | None = None, base_url: str | None = None, client: Any | None = None) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import openai
            except ImportError as exc:
                raise RuntimeError("openai not installed; run: pip install 'codejury[openai]'") from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = openai.OpenAI(**kwargs)
        return self._client

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        api_messages: list[dict] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        api_messages += [{"role": m.role, "content": m.content} for m in messages]

        response = self._get_client().chat.completions.create(
            model=model,
            messages=api_messages,
            max_tokens=max_tokens,
        )
        return CompletionResult(text=choice_text(response), model=getattr(response, "model", None) or model)
