"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider

PROVIDERS = ("anthropic", "openai", "litellm")

# finder, challenger, and judge can inherit the base backend or name their own. A distinct judge
# makes deletion require two independent reads, and with none set nothing is refuted, recall-safe.
ROLES = ("finder", "challenger", "judge")

_DEFAULT_TIMEOUT = 240.0


def env_defaults() -> dict:
    """The env-backed defaults, read on call rather than frozen at import, so a CLI that loaded a
    .env first sees them."""
    return {
        "provider": os.environ.get("CODEJURY_PROVIDER", "anthropic"),
        "model": os.environ.get("CODEJURY_MODEL", "claude-opus-4-8"),
        "api_key": os.environ.get("CODEJURY_API_KEY"),
        "api_base": os.environ.get("CODEJURY_API_BASE"),
        "wire_api": os.environ.get("CODEJURY_WIRE_API", "chat"),
        "retries": int(os.environ.get("CODEJURY_RETRIES", "2")),
        "timeout": float(os.environ.get("CODEJURY_TIMEOUT") or _DEFAULT_TIMEOUT),
        "role_backends": {
            role: {
                "provider": os.environ.get(f"CODEJURY_{role.upper()}_PROVIDER"),
                "model": os.environ.get(f"CODEJURY_{role.upper()}_MODEL"),
                "api_key": os.environ.get(f"CODEJURY_{role.upper()}_API_KEY"),
                "api_base": os.environ.get(f"CODEJURY_{role.upper()}_API_BASE"),
                "wire_api": os.environ.get(f"CODEJURY_{role.upper()}_WIRE_API"),
            }
            for role in ROLES
        },
    }


def make_provider(
    name: str,
    *,
    api_key: str | None = None,
    api_base: str | None = None,
    retries: int = 0,
    wire_api: str = "chat",
    timeout: float = _DEFAULT_TIMEOUT,
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
