"""make_provider selects a backend and applies retry wrapping. The other tests monkeypatch
the factory out, so this is the only place its real selection and RetryProvider branch run.
Construction is lazy, no SDK or key is touched until a call is made."""

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.factory import make_provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider


def test_selects_provider_by_name():
    assert isinstance(make_provider("openai"), OpenAIProvider)
    assert isinstance(make_provider("litellm"), LiteLLMProvider)
    assert isinstance(make_provider("anthropic"), AnthropicProvider)


def test_unknown_name_defaults_to_anthropic():
    assert isinstance(make_provider("something-else"), AnthropicProvider)


def test_no_retries_leaves_the_provider_unwrapped():
    provider = make_provider("openai", retries=0)
    assert isinstance(provider, OpenAIProvider)


def test_retries_wrap_in_retry_provider_with_one_extra_attempt():
    provider = make_provider("litellm", retries=2)
    assert isinstance(provider, RetryProvider)
    assert isinstance(provider._inner, LiteLLMProvider)
    assert provider._max_attempts == 3
