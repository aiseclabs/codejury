"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider

PROVIDERS = ("anthropic", "openai", "litellm")
DEFAULT_MODEL = os.environ.get("CODEJURY_MODEL", "claude-sonnet-4-6")
DEFAULT_API_BASE = os.environ.get("CODEJURY_API_BASE")
DEFAULT_API_KEY = os.environ.get("CODEJURY_API_KEY")
# adversarial mode: per-role model overrides; each falls back to the base model.
DEFAULT_FINDER_MODEL = os.environ.get("CODEJURY_FINDER_MODEL")
DEFAULT_CHALLENGER_MODEL = os.environ.get("CODEJURY_CHALLENGER_MODEL")
DEFAULT_JUDGE_MODEL = os.environ.get("CODEJURY_JUDGE_MODEL")


def make_provider(
    name: str, *, api_key: str | None = None, api_base: str | None = None, retries: int = 0
) -> Provider:
    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, base_url=api_base)
    elif name == "litellm":
        provider = LiteLLMProvider(api_key=api_key, api_base=api_base)
    else:
        provider = AnthropicProvider(api_key=api_key, base_url=api_base)
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1)
    return provider
