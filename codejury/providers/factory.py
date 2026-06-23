"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider

PROVIDERS = ("anthropic", "openai", "litellm")
# the default provider, env-backed like the model and the checker provider, so the main
# backend can be set once in the environment instead of named on every invocation
DEFAULT_PROVIDER = os.environ.get("CODEJURY_PROVIDER", "anthropic")
DEFAULT_MODEL = os.environ.get("CODEJURY_MODEL", "claude-opus-4-8")
DEFAULT_API_BASE = os.environ.get("CODEJURY_API_BASE")
DEFAULT_API_KEY = os.environ.get("CODEJURY_API_KEY")
# retry attempts on a transient failure, env-backed like the rest of the backend config so
# CI can set it once, symmetric with the timeout knobs that were already env-only
DEFAULT_RETRIES = int(os.environ.get("CODEJURY_RETRIES", "2"))
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
# per-request deadline in seconds. Short enough that a hung or stalled call returns to the
# retry layer to back off rather than holding a worker until a far longer ceiling, see the
# blind run where a 600s timeout let one stalled call stack into hours.
DEFAULT_TIMEOUT = float(os.environ.get("CODEJURY_TIMEOUT", "240"))
# the outer hard deadline the retry layer enforces with a daemon thread, the bound the SDK
# timeout failed to apply against a proxy that holds the connection open. Shorter than the SDK
# timeout so it is the one that actually fires on a stalled call.
DEFAULT_HARD_TIMEOUT = float(os.environ.get("CODEJURY_HARD_TIMEOUT", "180"))


def make_provider(
    name: str, *, api_key: str | None = None, api_base: str | None = None, retries: int = 0,
    wire_api: str = "chat", timeout: float = DEFAULT_TIMEOUT
) -> Provider:
    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, base_url=api_base, wire_api=wire_api, timeout=timeout)
    elif name == "litellm":
        provider = LiteLLMProvider(api_key=api_key, api_base=api_base, timeout=timeout)
    else:
        provider = AnthropicProvider(api_key=api_key, base_url=api_base, timeout=timeout)
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1, hard_timeout=DEFAULT_HARD_TIMEOUT)
    return provider
