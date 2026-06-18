"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider

PROVIDERS = ("anthropic", "openai", "litellm")
DEFAULT_MODEL = os.environ.get("CODEJURY_MODEL", "claude-opus-4-8")
DEFAULT_API_BASE = os.environ.get("CODEJURY_API_BASE")
DEFAULT_API_KEY = os.environ.get("CODEJURY_API_KEY")
DEFAULT_FINDER_MODEL = os.environ.get("CODEJURY_FINDER_MODEL")
DEFAULT_CHALLENGER_MODEL = os.environ.get("CODEJURY_CHALLENGER_MODEL")
DEFAULT_JUDGE_MODEL = os.environ.get("CODEJURY_JUDGE_MODEL")

# The repo-review refutation checker, a deliberately DIFFERENT model from the skeptic, so a
# deletion needs two models with uncorrelated blind spots to agree. A same-model second read
# shares the skeptic's blind spot and rubber-stamps a wrong refutation, as it did on the
# backed buyout reentrancy. Defaults to an OpenAI model so the second opinion is cross-vendor.
# With no checker model set, no finding is refuted, the recall-safe default.
DEFAULT_CHECKER_PROVIDER = os.environ.get("CODEJURY_CHECKER_PROVIDER", "openai")
DEFAULT_CHECKER_MODEL = os.environ.get("CODEJURY_CHECKER_MODEL")
DEFAULT_CHECKER_API_BASE = os.environ.get("CODEJURY_CHECKER_API_BASE")
DEFAULT_CHECKER_API_KEY = os.environ.get("CODEJURY_CHECKER_API_KEY")
# gpt-5 reasoning models reach this proxy through the Responses API, see ~/.codex wire_api.
DEFAULT_CHECKER_WIRE_API = os.environ.get("CODEJURY_CHECKER_WIRE_API", "responses")


def make_provider(
    name: str, *, api_key: str | None = None, api_base: str | None = None, retries: int = 0,
    wire_api: str = "chat"
) -> Provider:
    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, base_url=api_base, wire_api=wire_api)
    elif name == "litellm":
        provider = LiteLLMProvider(api_key=api_key, api_base=api_base)
    else:
        provider = AnthropicProvider(api_key=api_key, base_url=api_base)
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1)
    return provider
