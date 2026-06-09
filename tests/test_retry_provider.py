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
