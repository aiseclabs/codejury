"""RetryProvider -- wrap any Provider, retrying complete() on transient failure.

Real model calls fail intermittently (timeouts, rate limits). This decorator
retries with linear backoff and re-raises the last error once attempts are
exhausted. ``sleep`` is injectable so tests do not actually wait.
"""

from __future__ import annotations

import time
from typing import Callable

from codejury.providers.base import CompletionResult, Message, Provider


class RetryProvider(Provider):
    def __init__(
        self,
        inner: Provider,
        *,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._inner = inner
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._sleep = sleep

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        for attempt in range(1, self._max_attempts + 1):
            try:
                return self._inner.complete(
                    system=system, messages=messages, model=model, max_tokens=max_tokens, cache=cache
                )
            except Exception:
                if attempt == self._max_attempts:
                    raise
                self._sleep(self._base_delay * attempt)
        raise AssertionError("unreachable")  # pragma: no cover
