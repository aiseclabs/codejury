"""AnthropicProvider -- Provider backed by the Anthropic Messages API.

When ``cache`` is set, the system prompt is marked with an ephemeral
cache_control block; the capability checklist is large and reused across
artifacts, so caching it is the high-value target.

The Anthropic client is injectable so the mapping and caching logic can be
tested without the SDK or an API key. Constructed lazily otherwise, reading
ANTHROPIC_API_KEY from the environment.
"""

from __future__ import annotations

from typing import Any

from codejury.providers.base import CompletionResult, Message, Provider


class AnthropicProvider(Provider):
    def __init__(self, *, api_key: str | None = None, client: Any | None = None) -> None:
        self._api_key = api_key
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise RuntimeError(
                    "anthropic SDK not installed; run: pip install 'codejury[anthropic]'"
                ) from exc
            self._client = anthropic.Anthropic(api_key=self._api_key)
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
        system_param: Any = system
        if cache and system:
            system_param = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]

        response = self._get_client().messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_param,
            messages=[{"role": m.role, "content": m.content} for m in messages],
        )
        return CompletionResult(text=_extract_text(response), model=getattr(response, "model", model))


def _extract_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if not isinstance(content, list):
        return str(content or "")
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if text:
            parts.append(str(text))
    return "".join(parts)
