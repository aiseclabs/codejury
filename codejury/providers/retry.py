"""RetryProvider: wrap any Provider, retrying complete() on transient failure.

Real model calls fail intermittently, on timeouts, blank bodies, or rate limits. This
decorator retries and re-raises the last error once attempts are exhausted. A rate limit is
handled specially: it honors the server's Retry-After when present, else backs off
exponentially with full jitter, since a large fan-out hammers the provider and a flat linear
retry just collides again at the same moment. Any other error keeps the simple linear
backoff. A 200 response with a blank body is a transient failure and is retried too, since an
empty reply is unusable and must not pass downstream as a clean no-findings result. ``sleep``
and ``rand`` are injectable so tests stay deterministic and do not actually wait.
"""

from __future__ import annotations

import random
import time
from typing import Callable

from codejury.providers.base import CompletionResult, Message, Provider


class EmptyResponseError(RuntimeError):
    """The provider returned a blank body on every attempt."""


def _is_rate_limit(exc: BaseException) -> bool:
    """Whether the error is a provider rate limit, matched on the SDK status code or the
    message rather than a provider name, so a new backend needs no code change."""
    if getattr(exc, "status_code", None) == 429:
        return True
    if "ratelimit" in type(exc).__name__.lower():
        return True
    msg = str(exc).lower()
    return "rate limit" in msg or "429" in msg or "too many requests" in msg


def _retry_after(exc: BaseException) -> float | None:
    """The server's Retry-After in seconds when the exception carries one, the wait it asks
    for, else None. Read from an SDK error's response headers or a retry_after attribute."""
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if headers is not None and hasattr(headers, "get"):
        raw = headers.get("retry-after") or headers.get("Retry-After")
        if raw is not None:
            try:
                return float(raw)
            except (TypeError, ValueError):
                pass
    raw = getattr(exc, "retry_after", None)
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


class RetryProvider(Provider):
    def __init__(
        self,
        inner: Provider,
        *,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        sleep: Callable[[float], None] = time.sleep,
        rand: Callable[[float, float], float] = random.uniform,
        retryable: tuple[type[BaseException], ...] = (Exception,),
    ) -> None:
        self._inner = inner
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._sleep = sleep
        self._rand = rand
        self._retryable = retryable

    def _backoff(self, exc: BaseException, attempt: int) -> float:
        """Seconds to wait before the next attempt. A rate limit honors the server's
        Retry-After, else backs off exponentially with full jitter so a fan-out's retries
        spread out instead of colliding again. Any other error keeps the linear backoff."""
        if _is_rate_limit(exc):
            after = _retry_after(exc)
            if after is not None:
                return min(after, self._max_delay)
            ceiling = min(self._base_delay * (2 ** (attempt - 1)), self._max_delay)
            return self._rand(0.0, ceiling)
        return self._base_delay * attempt

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
            except self._retryable as exc:
                if attempt == self._max_attempts:
                    raise
                self._sleep(self._backoff(exc, attempt))
                continue
            if result.text.strip():
                return result
            # 200 OK but blank body: a transient upstream hiccup, retry it
            if attempt == self._max_attempts:
                raise EmptyResponseError("provider returned a blank response after all attempts")
            self._sleep(self._base_delay * attempt)
        raise EmptyResponseError("retry provider was configured with no attempts")
