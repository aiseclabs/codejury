"""RetryProvider: wrap any Provider, retrying complete() on transient failure.

Real model calls fail intermittently, for example on timeouts or rate limits.
This decorator retries with linear backoff and re-raises the last error once
attempts are exhausted. A 200 response with a blank body is treated as a
transient failure and retried too, since an empty reply is unusable and must
not be passed downstream as a clean (no-findings) result. ``sleep`` is
injectable so tests do not actually wait.
"""

from __future__ import annotations

import time
from typing import Callable

from codejury.providers.base import CompletionResult, Message, Provider


class EmptyResponseError(RuntimeError):
    """The provider returned a blank body on every attempt."""


class RetryProvider(Provider):
    def __init__(
        self,
        inner: Provider,
        *,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        retryable: tuple[type[BaseException], ...] = (Exception,),
    ) -> None:
        self._inner = inner
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._sleep = sleep
        self._retryable = retryable

    @property
    def inner(self) -> Provider:
        """The wrapped provider, so callers need not reach into a private field."""
        return self._inner

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
                result = self._inner.complete(
                    system=system, messages=messages, model=model, max_tokens=max_tokens, cache=cache
                )
            except self._retryable:
                if attempt == self._max_attempts:
                    raise
                self._sleep(self._base_delay * attempt)
                continue
            if result.text.strip():
                return result
            # 200 OK but blank body: a transient upstream hiccup, retry it
            if attempt == self._max_attempts:
                raise EmptyResponseError("provider returned a blank response after all attempts")
            self._sleep(self._base_delay * attempt)
        raise EmptyResponseError("retry provider was configured with no attempts")
