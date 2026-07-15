"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider

PROVIDERS = ("anthropic", "openai", "litellm")
# the base backend is env-backed so callers can configure a default once.
DEFAULT_PROVIDER = os.environ.get("CODEJURY_PROVIDER", "anthropic")
DEFAULT_MODEL = os.environ.get("CODEJURY_MODEL", "claude-opus-4-8")
DEFAULT_API_KEY = os.environ.get("CODEJURY_API_KEY")
DEFAULT_API_BASE = os.environ.get("CODEJURY_API_BASE")
# the OpenAI wire is env-backed because GPT-5 reasoning models answer on Responses.
DEFAULT_WIRE_API = os.environ.get("CODEJURY_WIRE_API", "chat")
# retry count follows the same env-backed backend config as the timeout.
DEFAULT_RETRIES = int(os.environ.get("CODEJURY_RETRIES", "2"))

# finder, challenger, and judge can inherit the base backend or name their own.
# a distinct judge makes deletion require two independent reads, and with none set
# nothing is refuted, the recall-safe default.
ROLES = ("finder", "challenger", "judge")
DEFAULT_ROLE_BACKENDS = {
    role: {
        "provider": os.environ.get(f"CODEJURY_{role.upper()}_PROVIDER"),
        "model": os.environ.get(f"CODEJURY_{role.upper()}_MODEL"),
        "api_key": os.environ.get(f"CODEJURY_{role.upper()}_API_KEY"),
        "api_base": os.environ.get(f"CODEJURY_{role.upper()}_API_BASE"),
        "wire_api": os.environ.get(f"CODEJURY_{role.upper()}_WIRE_API"),
    }
    for role in ROLES
}
# the retry layer also enforces this deadline when an SDK timeout cannot.
DEFAULT_TIMEOUT = float(os.environ.get("CODEJURY_TIMEOUT", "240"))


def make_provider(
    name: str, *, api_key: str | None = None, api_base: str | None = None, retries: int = 0,
    wire_api: str = "chat", timeout: float = DEFAULT_TIMEOUT
) -> Provider:
    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, api_base=api_base, wire_api=wire_api, timeout=timeout)
    elif name == "litellm":
        provider = LiteLLMProvider(api_key=api_key, api_base=api_base, timeout=timeout)
    else:
        provider = AnthropicProvider(api_key=api_key, api_base=api_base, timeout=timeout)
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
    return provider
