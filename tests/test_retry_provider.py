import pytest

from codejury.providers.base import CompletionResult, Message, Provider
from codejury.providers.retry import RetryProvider


class _Flaky(Provider):
    """Fails `fail_times` times, then succeeds."""

    def __init__(self, fail_times):
        self._fail_times = fail_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise RuntimeError("transient")
        return CompletionResult(text="ok", model=kwargs["model"])


def _call(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8)


def test_retries_then_succeeds():
    slept = []
    inner = _Flaky(fail_times=2)
    provider = RetryProvider(inner, max_attempts=3, sleep=slept.append)
    assert _call(provider).text == "ok"
    assert inner.calls == 3       # two failures, one success
    assert slept == [1.0, 2.0]    # linear backoff between attempts, no real sleep


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
