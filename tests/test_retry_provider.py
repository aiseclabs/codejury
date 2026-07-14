import threading

import pytest

from codejury.providers.base import CompletionResult, Message, Provider
from codejury.providers.retry import EmptyResponseError, RetryProvider


class _Flaky(Provider):
    """Fails `fail_times` times, then succeeds."""

    def __init__(self, fail_times):
        self._fail_times = fail_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise RuntimeError("transient")
        return CompletionResult(text="ok")


def _call(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8)


def test_retries_then_succeeds():
    slept = []
    inner = _Flaky(fail_times=2)
    provider = RetryProvider(inner, max_attempts=3, sleep=slept.append)
    assert _call(provider).text == "ok"
    assert inner.calls == 3
    assert slept == [1.0, 2.0]


def test_reraises_after_exhausting_attempts():
    inner = _Flaky(fail_times=5)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(RuntimeError, match="transient"):
        _call(provider)
    assert inner.calls == 3


def test_no_retry_on_first_success():
    inner = _Flaky(fail_times=0)
    slept = []
    RetryProvider(inner, sleep=slept.append).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert inner.calls == 1
    assert slept == []


class _Blank(Provider):
    """Returns a blank body `blank_times` times, then a real reply."""

    def __init__(self, blank_times):
        self._blank_times = blank_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        return CompletionResult(text="" if self.calls <= self._blank_times else "ok")


def test_retries_blank_body_then_succeeds():
    inner = _Blank(blank_times=1)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    assert _call(provider).text == "ok"
    assert inner.calls == 2


def test_raises_when_body_blank_every_attempt():
    inner = _Blank(blank_times=5)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(EmptyResponseError):
        _call(provider)
    assert inner.calls == 3


class _RateLimited(Provider):
    """Fails with a given exception `fail_times` times, then succeeds."""

    def __init__(self, fail_times, exc):
        self._fail_times = fail_times
        self._exc = exc
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise self._exc
        return CompletionResult(text="ok")


def _rate_limit_exc():
    exc = RuntimeError("429 too many requests")
    exc.status_code = 429
    return exc


def test_rate_limit_backs_off_exponentially_with_jitter():
    # rand returns its upper bound, so the jittered wait equals the exponential ceiling: a
    # rate limit must grow the delay 1, 2, 4 instead of the linear 1, 2, 3 a flat retry gives
    slept = []
    inner = _RateLimited(fail_times=3, exc=_rate_limit_exc())
    provider = RetryProvider(inner, max_attempts=4, base_delay=1.0,
                             sleep=slept.append, rand=lambda _lo, hi: hi)
    assert _call(provider).text == "ok"
    assert slept == [1.0, 2.0, 4.0]


def test_rate_limit_honors_retry_after_header():
    # when the server sends Retry-After, that wait wins over the computed backoff
    class _Resp:
        headers = {"retry-after": "5"}

    exc = RuntimeError("rate limit")
    exc.response = _Resp()
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = RetryProvider(inner, max_attempts=3, base_delay=1.0,
                             sleep=slept.append, rand=lambda _lo, hi: hi)
    assert _call(provider).text == "ok"
    assert slept == [5.0]


def test_rate_limit_caps_at_max_delay():
    # a server Retry-After longer than max_delay is clamped, so one bad header cannot stall
    class _Resp:
        headers = {"retry-after": "9000"}

    exc = RuntimeError("rate limit")
    exc.response = _Resp()
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = RetryProvider(inner, max_attempts=3, base_delay=1.0, max_delay=30.0,
                             sleep=slept.append)
    assert _call(provider).text == "ok"
    assert slept == [30.0]


def test_non_rate_limit_keeps_linear_backoff():
    # a plain transient error is not a rate limit, so the simple linear backoff is unchanged
    slept = []
    inner = _RateLimited(fail_times=2, exc=RuntimeError("transient network blip"))
    provider = RetryProvider(inner, max_attempts=3, base_delay=1.0, sleep=slept.append)
    assert _call(provider).text == "ok"
    assert slept == [1.0, 2.0]


class _Hang(Provider):
    """Blocks on complete() until released, the proxy-holds-the-connection failure an SDK
    timeout does not catch."""

    def __init__(self):
        self.release = threading.Event()
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        self.release.wait()
        return CompletionResult(text="late")


def test_hard_timeout_aborts_a_hung_call():
    # a call that never returns is abandoned as a TimeoutError once the deadline passes,
    # instead of hanging forever, so the run survives a stalled provider
    inner = _Hang()
    provider = RetryProvider(inner, max_attempts=1, hard_timeout=0.2, sleep=lambda _: None)
    try:
        with pytest.raises(TimeoutError):
            _call(provider)
        assert inner.calls == 1
    finally:
        inner.release.set()   # let the abandoned daemon thread finish, no leak across tests


def test_hard_timeout_retries_then_recovers():
    # the deadline failure feeds the retry loop, so a one-off stall is retried and recovers
    inner = _Hang()
    inner.release.set()   # second attempt returns immediately
    provider = RetryProvider(inner, max_attempts=2, hard_timeout=5.0, sleep=lambda _: None)
    assert _call(provider).text == "late"


def test_no_hard_timeout_leaves_call_unbounded():
    # without a deadline the inner call runs to completion, unbounded
    inner = _Flaky(fail_times=0)
    provider = RetryProvider(inner)
    assert _call(provider).text == "ok"
