"""MockProvider -- a Provider that returns canned text instead of calling a model.

Used for the end-to-end dry-run and for tests, so the pipeline can run with no
API key and deterministic output. It holds no parsing or audit logic: it returns
whatever text it was configured with and records each call for inspection.
"""

from __future__ import annotations

from codejury.providers.base import CompletionResult, Message, Provider


class MockProvider(Provider):
    def __init__(self, *, responses: list[str] | None = None, default: str = "") -> None:
        # responses are returned in order, one per call; once exhausted, `default`
        # is returned for every further call.
        self._responses = list(responses or [])
        self._default = default
        self.calls: list[dict] = []

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        self.calls.append({"system": system, "messages": messages, "model": model})
        text = self._responses.pop(0) if self._responses else self._default
        return CompletionResult(text=text)
