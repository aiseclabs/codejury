"""Provider ABC and its typed input/output.

Deliberately minimal: one synchronous, non-streaming ``complete``. Streaming and
tool-calling are intentionally left out until a concrete need appears, so the
interface does not over-commit early.

``cache`` is a portable hint, not a guarantee: Anthropic supports prompt caching
natively, OpenAI does not, LiteLLM depends on the backend. Each provider decides
how to map the hint onto its own implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

Role = Literal["user", "assistant"]


@dataclass(frozen=True, kw_only=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True, kw_only=True)
class CompletionResult:
    text: str
    model: str = ""  # the model the provider actually resolved and used


class Provider(ABC):
    @abstractmethod
    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult: ...
